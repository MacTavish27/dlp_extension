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
        Schema::create('dlp_incidents', function (Blueprint $table) {
            $table->id();
            $table->foreignId('dlp_policy_id')->constrained()->cascadeOnDelete();
            $table->string('user_identifier')->nullable();
            $table->string('domain');
            $table->string('action_taken');
            $table->string('masked_sample')->nullable();
            $table->timestamp('occurred_at');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dlp_incidents');
    }
};
