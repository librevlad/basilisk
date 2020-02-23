<?php

namespace Librevlad\Basilisk\Git;

class Parser {

    public const objectPattern = '~[a-f0-9]{40}~ims';
    public const packPattern = '~pack-[a-f0-9]{40}~ims';

    public static function is_git_object( $filename ) {
        return preg_match( self::objectPattern, $filename );
    }

    public static function packs( $text ) {

        if ( ! preg_match_all( self::packPattern, $text, $packs ) ) {
            return [];
        }

        return $packs[ 0 ];
    }

    public static function objects( $text ) {

        if ( ! preg_match_all( self::objectPattern, $text, $objects ) ) {
            return [];
        }

        return $objects[ 0 ];
    }
}
