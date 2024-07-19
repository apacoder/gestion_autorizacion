<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\Key;
use Illuminate\Database\Eloquent\Model;

class GestionAutorizacionMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // Obtenemos las cookies y el token CSRF del header
        $accessToken       = $request->cookie('ga_access_token');
        $refreshToken      = $request->cookie('ga_refresh_token');
        $csrfTokenCookie   = $request->cookie('ga_csrf_token');
        $csrfTokenHeader   = $request->header('X-GA-CSRF-TOKEN');
        
        // Verificamos que las cookies existan
        if (!$accessToken || !$refreshToken || !$csrfTokenCookie || !$csrfTokenHeader) 
            return response()->json(['status' => 'error', 'message' => 'No autorizado'], 401);

        // Verificamos que el CSRF token sea válido
        if ($csrfTokenCookie !== $csrfTokenHeader) 
            return response()->json(['status' => 'error', 'message' => 'CSRF inválido'], 401);
        
        try {
            // Intentamos decodificar el token de acceso
            $payload = JWT::decode($accessToken, new Key(env('API_GA_JWT_SECRET'), 'HS256'));

            // Casteamos el payload a un objeto que extiende de Illuminate\Database\Eloquent\Model
            $jwt = new JWTPayload($payload);
            
            // Finalmente, agregamos el payload decodificado a la solicitud
            $request->merge(['jwt' => $jwt]);
            
        } catch (ExpiredException $e) {
            return response()->json(['status' => 'error', 'message' => 'Token expirado'           ], 401);
        } catch (SignatureInvalidException $e) {
            return response()->json(['status' => 'error', 'message' => 'Firma del token inválida' ], 401);
        } catch (BeforeValidException $e) {
            return response()->json(['status' => 'error', 'message' => 'Token no válido aún'      ], 401);
        } catch (\UnexpectedValueException $e) {
            return response()->json(['status' => 'error', 'message' => 'Token no válido'          ], 401);
        }

        // Si el token es válido, permitimos que la solicitud continúe
        return $next($request);
    }
}

// Clase auxiliar para manejar el payload del token JWT e indexarlo en el request
class JWTPayload extends Model {
    public function __construct($data = []) {
        foreach ($data as $key => $value) $this->$key = $value;
    }
}