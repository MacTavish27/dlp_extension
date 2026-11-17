<?php

use App\Http\Controllers\Api\DlpController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1/dlp')->group(function () {
    Route::get('/policies', [DlpController::class, 'policies']);
    Route::post('/incidents', [DlpController::class, 'logIncident']);
});
