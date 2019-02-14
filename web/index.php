<?php

require_once __DIR__ . '/../vendor/autoload.php';

use Bigcommerce\Api\Client as Bigcommerce;
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

//Redis is not free with heroku... this means that this doesn't work properly

$app = new Application();
$app['debug'] = true;

$app->get('/load', function (Request $request) use ($app) {

    $data = verifySignedRequest($request->get('signed_payload'));
    if (empty($data)) {
        return 'Invalid signed_payload.';
    }
    $headers = ['Access-Control-Allow-Origin' => '*'];

    $storeHash = 'u8stgwcn9s';
    configureBCApi($storeHash);
    $bcClient = Bigcommerce::getConnection();

    $currentConnection = $bcClient->get('https://api.bigcommerce.com/stores/u8stgwcn9s/v3/tax/connect/SampleTaxProvider', $data);
    $message = "Welcome Back";

    $htmlContent = (new Handlebars())->render(file_get_contents(__DIR__ . '/../templates/details-form.html'), []);
    if ($currentConnection && $currentConnection->data && $currentConnection->data->configured) {
        $htmlContent = (new Handlebars())->render(file_get_contents(__DIR__ . '/../templates/celebrate.html'), ['userName' => $currentConnection->data->username, 'message' => $message]);
    }
    $response = new Response($htmlContent, 200, $headers);

    return $response;
});

$app->get('/auth/callback', function (Request $request) use ($app) {
    $payload = [
        'client_id' => clientId(),
        'client_secret' => clientSecret(),
        'redirect_uri' => callbackUrl(),
        'grant_type' => 'authorization_code',
        'code' => $request->get('code'),
        'scope' => $request->get('scope'),
        'context' => $request->get('context'),
    ];

    $client = new Client(bcAuthService());
    $req = $client->post('/oauth2/token', [], $payload, [
        'exceptions' => false,
    ]);
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
    return '[Remove User] ' . $data['user']['email'];
});

$app->post('/update-credentials', function (Request $request) use ($app) {
    $headers = ['Access-Control-Allow-Origin' => '*'];
    $data = [
        'username' => $request->get('userName'),
        'password' => $request->get('password')
    ];
    $storeHash = 'u8stgwcn9s';
    configureBCApi($storeHash);
    $bcClient = Bigcommerce::getConnection();

    $bcClient->put('https://api.bigcommerce.com/stores/u8stgwcn9s/v3/tax/connect/SampleTaxProvider', $data);
    $results = $bcClient->get('https://api.bigcommerce.com/stores/u8stgwcn9s/v3/tax/connect/SampleTaxProvider', $data);

    $message = 'Connection failed, probably due to v3 API-Proxy not being released yet. Try again later';
    if ($results) {
        $message = 'Congratulations you are now connected to BigCommerce. Great work';
    }

    $htmlContent = (new Handlebars())->render(file_get_contents(__DIR__ . '/../templates/celebrate.html'), ['userName' => $request->get('userName'), 'message' => $message]);
    $response = new Response($htmlContent, 200, $headers);

    return $response;
});

$app->post('/disconnect', function(){
    $storeHash = 'u8stgwcn9s';
    configureBCApi($storeHash);
    $bcClient = Bigcommerce::getConnection();
    $response =   $bcClient->delete('https://api.bigcommerce.com/stores/u8stgwcn9s/v3/tax/connect/SampleTaxProvider');


    $headers = ['Access-Control-Allow-Origin' => '*'];
    $htmlContent = 'You have been susccessfully disconnected.';
    $response = new Response($htmlContent, 200, $headers);

    return $response;
//    http_redirect('/load');
});

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
    $authData = json_decode('{"access_token":"p1qorxexea81jyodql7u7o1ojf7ojnn","scope":"store_v2_default store_v2_information users_basic_information","user":{"id":1098843,"username":"ben.pratt@bigcommerce.com","email":"ben.pratt@bigcommerce.com"},"context":"stores\/u8stgwcn9s"}');
    return $authData->access_token;
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

$app->run();
