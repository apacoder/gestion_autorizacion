<?php

use App\Http\Controllers\GoogleLoginController;
use Illuminate\Http\Request;
// use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/google/login'  , [GoogleLoginController::class, 'login'   ]);
Route::post('/google/logout' , [GoogleLoginController::class, 'logout'  ]);
Route::post('/google/refresh', [GoogleLoginController::class, 'refresh' ]);

Route::middleware('auth.ga')->get('/auth/user', function (Request $request) {
    $usuario = $request->jwt;
    unset($usuario->exp);
    return $request->jwt;
});


