<?php

class Filter {
    
    public static function sanitizeString($input) {
        $input = trim($input);
        $input = stripslashes($input);
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        return $input;
    }
    
    public static function sanitizeEmail($input) {
        $input = filter_var($input, FILTER_SANITIZE_EMAIL);
        return self::sanitizeString($input);
    }
    
    public static function sanitizeInt($input) {
        $input = filter_var($input, FILTER_SANITIZE_NUMBER_INT);
        return self::sanitizeString($input);
    }
    
    public static function sanitizeFloat($input) {
        $input = filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        return self::sanitizeString($input);
    }
    
    public static function sanitizeUrl($input) {
        $input = filter_var($input, FILTER_SANITIZE_URL);
        return self::sanitizeString($input);
    }
}
