<?php

use App\Http\Controllers\GoogleLoginController;
use Illuminate\Http\Request as HttpRequest;
use Illuminate\Support\Facades\Route;

Route::post('/google_one_tap/login',         [GoogleLoginController::class, 'login'         ]);
Route::post('/google_one_tap/logout',        [GoogleLoginController::class, 'logout'        ]);
Route::post('/google_one_tap/refresh_token', [GoogleLoginController::class, 'refresh_token' ]);

Route::post('/test_request', function(HttpRequest $request) {
    $csrfTokenHeader = $request->header('X-GA-CSRF-TOKEN');
    $csrfTokenCookie = $request->cookie('ga_csrf_token');

    return response()->json([
        'status'          => 'success',
        'csrfToken'       => $csrfTokenHeader,
        'csrfTokenCookie' => $csrfTokenCookie,
        'match'           => $csrfTokenHeader === $csrfTokenCookie
    ]);
});
