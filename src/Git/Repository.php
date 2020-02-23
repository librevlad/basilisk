<?php


namespace Librevlad\Basilisk\Git;


use Symfony\Component\Process\Process;

class Repository {

    public $path;

    public function __construct( $path ) {
        $this->path = $path . '/.git/';
    }

    public function filename_from_object_hash( $hash ) {
        return 'objects/' . substr( $hash, 0, 2 ) . '/' . substr( $hash, 2 );
    }

    public function object_hash_from_filename( $filename ) {
        $hash = str_replace( 'objects/', '', $filename );
        $hash = str_replace( '/', '', $hash );

        return Parser::is_git_object( $hash ) ? $hash : false;
    }

    public function catFileType( $filename ) {
        return $this->exec( [ 'git', 'cat-file', '-t', $filename ] );
    }

    public function objects() {
        return glob( $this->path . 'objects/*/*' );
    }

    public function commits() {
        $objects = $this->objects();
        $commits = [];
        foreach ( $objects as $fn ) {
            $fn   = str_replace( $this->path, '', $fn );
            $hash = $this->object_hash_from_filename( $fn );
            $t    = $this->catFileType( $hash );
            if ( $t == 'commit' ) {
                $commits [] = $hash;
            }
        }

        return $commits;
    }

    public function catFileContents( $filename ) {
        return $this->catFileContentsText( $filename );
    }

    public function catFileContentsText( $filename ) {
        return $this->exec( [ 'git', 'cat-file', '-p', $filename ] );
    }

    public function tree( $commit ) {
        $tree = [];

        if ( ! ( $this->exec( [ 'git', 'ls-tree', $commit ] ) ) ) {
            return [];
        }
        $explode = explode( PHP_EOL, $this->exec( [ 'git', 'ls-tree', $commit ] ) );
        foreach ( $explode as $line ) {
            $parts      = explode( "\t", $line );
            $otherParts = explode( " ", $parts[ 0 ] );

            $tree       [] = [
                'permissions' => $otherParts[ 0 ],
                'type'        => $otherParts[ 1 ],
                'hash'        => $otherParts[ 2 ],
                'filename'    => $parts[ 1 ],
            ];
        }


        return $tree;
    }

    protected function exec( $command ) {
        $p    = new Process( implode( " ", $command ), $this->path );
        $code = $p->run();
        $o    = trim( $p->getOutput() );

        return $code ? false : $o;
    }
}
