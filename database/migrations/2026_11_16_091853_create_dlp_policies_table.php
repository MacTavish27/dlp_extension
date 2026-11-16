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
        Schema::create('dlp_policies', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->enum('detection_type', ['regex', 'keyword', 'entropy'])->default('regex');
            $table->text('pattern'); 
            $table->enum('action', ['log', 'warn', 'block', 'redact'])->default('block');
            $table->enum('severity', ['low', 'medium', 'high', 'critical'])->default('high');
            $table->json('target_domains')->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dlp_policies');
    }
};
