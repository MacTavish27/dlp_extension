<?php

namespace App\Filament\Resources\DlpPolicies\Schemas;

use Filament\Schemas\Schema;
use Filament\Schemas\Components\Section;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\Toggle;
use Filament\Forms\Components\TagsInput;

class DlpPolicyForm
{
    public static function configure(Schema $schema): Schema
    {
        return $schema->components([
            Section::make('Rule Definition')
                ->schema([
                    TextInput::make('name')->required()->placeholder('e.g., AWS Access Key Leak'),

                    Select::make('detection_type')
                        ->options([
                            'regex' => 'Regular Expression (Regex)',
                            'keyword' => 'Keyword List (Comma-separated)',
                            'entropy' => 'High Entropy Threshold (e.g., 4.5)',
                        ])
                        ->required()
                        ->live(),

                    Textarea::make('pattern')->required()->helperText('For Regex, omit enclosing slashes (e.g., AKIA[0-9A-Z]{16})'),
                ])
                ->columns(2),

            Section::make('Enforcement & Scope')
                ->schema([
                    Select::make('action')
                        ->options([
                            'log' => 'Audit Log Only',
                            'warn' => 'Warn User (Allow Override)',
                            'block' => 'Hard Block Submission',
                            'redact' => 'Auto-Redact Sensitive String',
                        ])
                        ->required(),
                    Select::make('severity')
                        ->options([
                            'low' => 'Low',
                            'medium' => 'Medium',
                            'high' => 'High',
                            'critical' => 'Critical',
                        ])
                        ->required(),
                    TagsInput::make('target_domains')
                        ->placeholder('Add domain (leave empty for all AI sites)')
                        ->suggestions(['chatgpt.com', 'claude.ai', 'gemini.google.com']),
                    Toggle::make('is_active')->default(true),
                ])
                ->columns(2),
        ]);
    }
}
