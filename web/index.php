<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Bigcommerce\Api\Client as Bigcommerce;
use Firebase\JWT\JWT;
use Guzzle\Http\Client;
use Handlebars\Handlebars;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

const BC_AUTH_SERVICE = 'https://login.bigcommerce.com';
const BC_CLIENT_ID = '68dp2ybd4w2vbae9pvlznv6hrzh2db2';
const BC_CLIENT_SECRET = 'gzaw2tnmcmuz5n1ewooo8ve7pv97ch1';
const BC_CALLBACK_URL = 'https://sample-tax-app.herokuapp.com/auth/callback';
const APP_URL = 'https://sample-tax-app.herokuapp.com/';

//redis is not free with heroku

$app = new Application();
$app['debug'] = true;

$app->get('/load', function (Request $request) use ($app) {

    $data = verifySignedRequest($request->get('signed_payload'));
    if (empty($data)) {
        return 'Invalid signed_payload.';
    }
    $headers = ['Access-Control-Allow-Origin' => '*'];

    // Render the template with the recently purchased products fetched from the BigCommerce server.
    $htmlContent = (new Handlebars())->render(file_get_contents(__DIR__ . '/../templates/details-form.html'), []);
    $htmlContent = str_ireplace('http', 'https', $htmlContent); // Ensures we have HTTPS links, which for some reason we don't always get.
    $response = new Response($htmlContent, 200, $headers);

    /*** TESTING THE API **/
    $storeHash = 'u8stgwcn9s';
    configureBCApi($storeHash);

    $userName = 'apples';
    $password = 'carrots';
    credentialise($userName, $password);
    /*** !TESTING THE API **/

    return $response;
});

$app->get('/auth/callback', function (Request $request) use ($app) {

    $payload = array(
        'client_id' => clientId(),
        'client_secret' => clientSecret(),
        'redirect_uri' => callbackUrl(),
        'grant_type' => 'authorization_code',
        'code' => $request->get('code'),
        'scope' => $request->get('scope'),
        'context' => $request->get('context'),
    );

    $client = new Client(bcAuthService());
    $req = $client->post('/oauth2/token', array(), $payload, array(
        'exceptions' => false,
    ));
    $resp = $req->send();

    if ($resp->getStatusCode() == 200) {
        $data = $resp->json();
        return 'Hello ' . json_encode($data);
    } else {
        return 'Something went wrong... [' . $resp->getStatusCode() . '] ' . $resp->getBody();
    }

});

// Endpoint for removing users in a multi-user setup
$app->get('/remove-user', function (Request $request) use ($app) {
    $data = verifySignedRequest($request->get('signed_payload'));
    if (empty($data)) {
        return 'Invalid signed_payload.';
    }

//	$key = getUserKey($data['store_hash'], $data['user']['email']);
//	$redis = new Credis_Client('localhost');
//	$redis->del($key);
    return '[Remove User] ' . $data['user']['email'];
});

/**
 * GET /storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html
 * Fetches the "Recently Purchased Products" HTML block and displays it in the frontend.
 */
$app->get('/storefront/{storeHash}/customers/{jwtToken}/recently_purchased.html', function ($storeHash, $jwtToken) use ($app) {
    $headers = ['Access-Control-Allow-Origin' => '*'];
    try {
        // First let's get the customer's ID from the token and confirm that they're who they say they are.
        $customerId = getCustomerIdFromToken($jwtToken);

        // Next let's initialize the BigCommerce API for the store requested so we can pull data from it.
        configureBCApi($storeHash);

        // Generate the recently purchased products HTML
        $recentlyPurchasedProductsHtml = getRecentlyPurchasedProductsHtml($storeHash, $customerId);

        // Now respond with the generated HTML
        $response = new Response($recentlyPurchasedProductsHtml, 200, $headers);
    } catch (Exception $e) {
        error_log("Error occurred while trying to get recently purchased items: {$e->getMessage()}");
        $response = new Response("", 500, $headers); // Empty string here to make sure we don't display any errors in the storefront.
    }

    return $response;
});


$app->get('/enterCredentials', function ($storeHash) use ($app) {
    $userName = 'apples';
    $password = 'carrots';
    credentialise($userName, $password);
});

function credentialise($userName, $password)
{
    $client = new Client(bcAuthService());
    $payload = [
        'username' => $userName,
        'password' => $password
    ];
    $headers = [
        'client_id' => clientId(),
        'auth_token' => getAuthToken('u8stgwcn9s'),
        'store_hash' => 'u8stgwcn9s',
        'access_token' => 'fq7dvv6by8tzwincwe1sjc041abmrpv',
    ];

    $headers = json_decode('{"access_token":"fq7dvv6by8tzwincwe1sjc041abmrpv","scope":"store_v2_default store_v2_information store_v2_products_read_only users_basic_information","user":{"id":1098843,"username":"ben.pratt@bigcommerce.com","email":"ben.pratt@bigcommerce.com"},"context":"stores\/u8stgwcn9s"}');

//    $headers = [
//        'access_token' => 'fq7dvv6by8tzwincwe1sjc041abmrpv',
//        'client_id' => '68dp2ybd4w2vbae9pvlznv6hrzh2db2'
//    ];
    $url = 'https://api.bigcommerce.com/stores/u8stgwcn9s/v2/orders/';
    $req = $client->get($url, $headers, ['exceptions' => false]);

//    $url = 'https://api.bigcommerce.com/stores/u8stgwcn9s/v1/tax/connect/SampleTaxProvider';
//    $req = $client->post($url, [], $payload, ['exceptions' => false]);


    $resp = $req->send();

    var_dump('Url: ' . $url . ' returned with code: ' . $resp->getStatusCode());
}


/**
 * Gets the HTML block that displays the recently purchased products for a store.
 * @param string $storeHash
 * @param string $customerId
 * @return string HTML content to display in the storefront
 */
function getRecentlyPurchasedProductsHtml($storeHash, $customerId)
{
//	$redis = new Credis_Client('localhost');
    $cacheKey = "stores/{$storeHash}/customers/{$customerId}/recently_purchased_products.html";
    $cacheLifetime = 60 * 5; // Set a 5 minute cache lifetime for this HTML block.

    // First let's see if we can find he HTML block in the cache so we don't have to reach out to BigCommerce's servers.
    $cachedContent = json_decode($redis->get($cacheKey));
    if (!empty($cachedContent) && (int)$cachedContent->expiresAt > time()) { // Ensure the cache has not expired as well.
        return $cachedContent->content;
    }

    // Whelp looks like we couldn't find the HTML block in the cache, so we'll have to compile it ourselves.
    // First let's get all the customer's recently purchased products.
    $products = getRecentlyPurchasedProducts($customerId);

    // Render the template with the recently purchased products fetched from the BigCommerce server.
    $htmlContent = (new Handlebars())->render(
        file_get_contents('templates/recently_purchased.html'),
        ['products' => $products]
    );
    $htmlContent = str_ireplace('http', 'https', $htmlContent); // Ensures we have HTTPS links, which for some reason we don't always get.

    // Save the HTML content in the cache so we don't have to reach out to BigCommece's server too often.
//	$redis->set($cacheKey, json_encode([ 'content' => $htmlContent, 'expiresAt' => time() + $cacheLifetime]));

    return $htmlContent;
}

/**
 * Look at each of the customer's orders, and each of their order products and then pull down each product resource
 * that was purchased.
 * @param string $customerId ID of the customer that we want to retrieve the recently purchased products list for.
 * @return array<Bigcommerce\Resources\Product> An array of products from the BigCommerce API
 */
function getRecentlyPurchasedProducts($customerId)
{
    $products = [];

    foreach (Bigcommerce::getOrders(['customer_id' => $customerId]) as $order) {
        foreach (Bigcommerce::getOrderProducts($order->id) as $orderProduct) {
            array_push($products, Bigcommerce::getProduct($orderProduct->product_id));
        }
    }

    return $products;
}

/**
 * Configure the static BigCommerce API client with the authorized app's auth token, the client ID from the environment
 * and the store's hash as provided.
 * @param string $storeHash Store hash to point the BigCommece API to for outgoing requests.
 */
function configureBCApi($storeHash)
{
    Bigcommerce::configure(array(
        'client_id' => clientId(),
        'auth_token' => getAuthToken($storeHash),
        'store_hash' => $storeHash
    ));
}

/**
 * @param string $storeHash store's hash that we want the access token for
 * @return string the oauth Access (aka Auth) Token to use in API requests.
 */
function getAuthToken($storeHash)
{
    $authData = json_decode('{"access_token":"fq7dvv6by8tzwincwe1sjc041abmrpv","scope":"store_v2_default store_v2_information store_v2_products_read_only users_basic_information","user":{"id":1098843,"username":"ben.pratt@bigcommerce.com","email":"ben.pratt@bigcommerce.com"},"context":"stores\/u8stgwcn9s"}');
    return $authData->access_token;
}

/**
 * @param string $jwtToken customer's JWT token sent from the storefront.
 * @return string customer's ID decoded and verified
 */
function getCustomerIdFromToken($jwtToken)
{
    $signedData = JWT::decode($jwtToken, clientSecret(), array('HS256', 'HS384', 'HS512', 'RS256'));
    return $signedData->customer->id;
}

/**
 * This is used by the `GET /load` endpoint to load the app in the BigCommerce control panel
 * @param string $signedRequest Pull signed data to verify it.
 * @return array|null null if bad request, array of data otherwise
 */
function verifySignedRequest($signedRequest)
{
    list($encodedData, $encodedSignature) = explode('.', $signedRequest, 2);

    // decode the data
    $signature = base64_decode($encodedSignature);
    $jsonStr = base64_decode($encodedData);
    $data = json_decode($jsonStr, true);

    // confirm the signature
    $expectedSignature = hash_hmac('sha256', $jsonStr, clientSecret(), $raw = false);
    if (!hash_equals($expectedSignature, $signature)) {
        error_log('Bad signed request from BigCommerce!');
        return null;
    }
    return $data;
}

/**
 * @return string Get the app's client ID from the environment vars
 */
function clientId()
{
    $clientId = BC_CLIENT_ID;
    return $clientId ?: '';
}

/**
 * @return string Get the app's client secret from the environment vars
 */
function clientSecret()
{
    $clientSecret = BC_CLIENT_SECRET;
    return $clientSecret ?: '';
}

/**
 * @return string Get the callback URL from the environment vars
 */
function callbackUrl()
{
    $callbackUrl = BC_CALLBACK_URL;
    return $callbackUrl ?: '';
}

/**
 * @return string Get auth service URL from the environment vars
 */
function bcAuthService()
{
    $bcAuthService = BC_AUTH_SERVICE;
    return $bcAuthService ?: '';
}

function getUserKey($storeHash, $email)
{
    return "kitty.php:$storeHash:$email";
}

// redis set key kitty.php:u8stgwcn9s:ben.pratt@bigcommerce.com
//store hash u8stgwcn9s


$app->run();


