<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\DlpController;

Route::prefix('v1/dlp')->group(function () {
    Route::get('/policies', [DlpController::class, 'policies']);
    Route::post('/incidents', [DlpController::class, 'logIncident']);
});
