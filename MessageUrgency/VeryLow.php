<?php
declare(strict_types=1);

namespace WebPush\MessageUrgency;

use WebPush\Contract\MessageUrgency;

final class VeryLow implements MessageUrgency
{
    public function name(): string
    {
        return 'very-low';
    }
}