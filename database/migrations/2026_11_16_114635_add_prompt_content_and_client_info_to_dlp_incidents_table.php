<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('dlp_incidents', function (Blueprint $table) {
            $table->longText('prompt_content')->nullable()->after('masked_sample');
            $table->string('client_ip', 45)->nullable()->after('prompt_content');
            $table->text('user_agent')->nullable()->after('client_ip');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('dlp_incidents', function (Blueprint $table) {
            $table->dropColumn(['prompt_content', 'client_ip', 'user_agent']);
        });
    }
};
