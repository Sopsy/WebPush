<?php
declare(strict_types=1);

namespace WebPush\MessageUrgency;

use WebPush\Contract\MessageUrgency;

final class High implements MessageUrgency
{
    public function name(): string
    {
        return 'high';
    }
}