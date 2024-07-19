<?php

namespace App\Http\Controllers;

use App\Models\Usuario;
use Illuminate\Http\Request;
use Google_Client;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\DB;

class GoogleLoginController extends Controller
{
    public function login(Request $request) {
        // Verificamos el token de Google
        $client  = new Google_Client(['client_id' => env('GOOGLE_CLIENT_ID')]);  
        $payload = $client->verifyIdToken($request->credential);

        // Si el token no es válido, retornamos un error
        if(!$payload) 
            return response()->json(['status' => 'error', 'message' => 'Token ID inválido'], 401);

        $email = $payload['email'];

        // Verificamos que el dominio del correo sea válido
        [$user, $domain] = explode('@', $email);

        // Si el dominio no es válido, retornamos un error
        if ($domain !== env('ALLOWED_EMAIL_DOMAIN')) 
            return response()->json(['status' => 'error', 'message' => 'Dominio inválido'], 500);

        $name = $payload['name'];

        $user = (array) DB::table('usuarios')->where('correo', $email)->first();
        $user['google_name'] = $name;
        
        // Token de acceso
        $user['exp'] = time() + 60 * 60; // 1 hora
        $accessToken  = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');

        // Token de refresco
        $user['exp'] = time() + 60 * 60 * 8 ; // 8 horas
        $refreshToken = JWT::encode(payload: $user, key: env('API_GA_JWT_SECRET'), alg: 'HS256');

        // CSRF Token
        $csrfToken    = bin2hex(random_bytes(32));
        
        return response()->json([
            'user'          => $user,
            'ga_csrf_token' => $csrfToken,
        ])->withCookie(self::createCookie(name: 'ga_access_token' , value: $accessToken ))
          ->withCookie(self::createCookie(name: 'ga_refresh_token', value: $refreshToken))
          ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: $csrfToken   ));
    }

    public function createRespsonse($email, $cfsToken){
        return response()->json([
            'email' => Usuario::where('correo', $email)->first(),
            'cfsToken' => $cfsToken
        ]);
    }
    
    public function createCookie($name, $value){
        return cookie( name: $name, value: $value, minutes: 60, path: null, domain: null, secure: true, httpOnly: true, sameSite: 'None' );
    }

}
