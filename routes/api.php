<?php

use App\Http\Controllers\GoogleLoginController;
use Illuminate\Http\Request as HttpRequest;
use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Route;

Route::post('/google_one_tap/login',         [GoogleLoginController::class, 'login'         ]);
Route::post('/google_one_tap/logout',        [GoogleLoginController::class, 'logout'        ]);
Route::post('/google_one_tap/refresh_token', [GoogleLoginController::class, 'refresh_token' ]);

Route::get('/auth/user', function(Request $request) {
    return response()->json([
        'nombre' => 'Jhon Doe',
        'email'  => 'asdsad',
    ]);
});
