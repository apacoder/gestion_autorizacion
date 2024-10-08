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
        $google_user = (object) $client->verifyIdToken($request->credential);

        // Si el token no es válido, retornamos un error
        if(!$google_user) 
            return response()->json(['status' => 'error', 'message' => 'Token ID inválido'], 401);

        $email = $google_user->email;

        // Verificamos que el dominio del correo sea válido
        [$_, $domain] = explode('@', $email);

        // Si el dominio no es válido, retornamos un error
        if ($domain !== env('ALLOWED_EMAIL_DOMAIN')) 
            return response()->json(['status' => 'error', 'message' => 'Dominio inválido'], 500);

        // Buscamos al usuario en la base de datos
        $db_user = Usuario::where('correo', $email)->select('codigo', 'usuario')->first();

        // Si el usuario no existe, retornamos un error
        if(!$db_user)
            return response()->json(['status' => 'error', 'message' => 'No tienes acceso'], 401);
        
        // Creamos el payload del token
        $payload = [
            'codigo'  => $db_user->codigo,
            'usuario' => $db_user->usuario,
            'nombre'  => $google_user->name,
            'avatar'  => $google_user->picture,
        ];

        $response_user =  $payload;
        
        // Token de acceso
        $payload['exp'] = time() + 60 * 60; // 1 hora
        $accessToken  = JWT::encode(payload: $payload, key: env('API_GA_JWT_SECRET'), alg: 'HS256');

        // Token de refresco
        $payload['exp'] = time() + 60 * 60 * 8 ; // 8 horas
        $refreshToken = JWT::encode(payload: $payload, key: env('API_GA_JWT_SECRET'), alg: 'HS256');

        // CSRF Token
        $csrfToken    = bin2hex(random_bytes(32));

        // ELiminamos el timestamp de expiración
        unset($payload['exp']);
        
        return response()->json([
            'user'          => $response_user,
            'ga_csrf_token' => $csrfToken,
        ])->withCookie(self::createCookie(name: 'ga_access_token' , value: $accessToken ))
          ->withCookie(self::createCookie(name: 'ga_refresh_token', value: $refreshToken))
          ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: $csrfToken   ));
    }

    public function logout(Request $request){
        return response()
            ->json(['status' => 'success', 'message' => 'Sesión cerrada'])
            ->withCookie(self::createCookie(name: 'ga_access_token' , value: ''))
            ->withCookie(self::createCookie(name: 'ga_refresh_token', value: ''))
            ->withCookie(self::createCookie(name: 'ga_csrf_token'   , value: ''));
    }
    
    public function createCookie($name, $value) {
        return cookie( name: $name, value: $value, minutes: 60, path: null, domain: null, secure: true, sameSite: 'None' );
    }

}
