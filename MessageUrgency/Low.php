<?php
declare(strict_types=1);

namespace WebPush\MessageUrgency;

use WebPush\Contract\MessageUrgency;

final class Low implements MessageUrgency
{
    public function name(): string
    {
        return 'low';
    }
}