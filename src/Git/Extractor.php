<?php


namespace Librevlad\Basilisk\Git;


use Librevlad\Basilisk\OutputOnCommand;

class Extractor {
    use OutputOnCommand;

    public $path;
    public $extractedPath;
    /**
     * @var Repository
     */
    private $repo;

    protected $index = [];

    public function __construct( $path, $extractedPath = null ) {
        $this->path = $path;
        $this->extractedPath = $extractedPath ?? $this->path;
        $this->repo = new Repository( $path );
    }

    public function extract() {
        $this->line( 'Searching for commits' );
        $commits = $this->repo->commits();

        $this->info( 'Found ' . count( $commits ) . ' commits' );

        foreach ( $commits as $commit ) {
            $this->traverseCommit( $commit );
        }
    }

    protected function traverseCommit( $hash ) {
        $path = $this->extractedPath;
        $this->traverseTree( $hash, $path );
    }

    private function traverseTree( $hash, $path ) {

        $tree = $this->repo->tree( $hash );
        foreach ( $tree as $node ) {
            if ( $node[ 'type' ] == 'blob' ) {
                $extract_to      = $path . '/' . $node[ 'filename' ];
                $extract_to_real = $extract_to;
                $content         = $this->repo->catFileContentsText( $node[ 'hash' ] );
                $md5             = md5( $content );

                if ( file_exists( $extract_to ) && ( filesize( $extract_to ) > 0 ) ) {

                    if ( isset( $this->index[ $md5 ] ) && ( $this->index[ $md5 ] == $extract_to ) ) {
                        continue;
                    } elseif ( $md5 == md5( file_get_contents( $extract_to ) ) ) {
                        $this->index[ $md5 ] = $extract_to;
                        continue;
                    } else {
                        $extract_to_real = $path . '/' . $node[ 'filename' ] . '__' . $md5 . '__' . $node[ 'filename' ];
                    }
                }
                // file does not exist or we have a different name
                prepareDir( $extract_to_real );
                $this->info( $extract_to_real );
                file_put_contents( $extract_to_real, $content );
                $this->index[ $md5 ] = $extract_to;
            } else {
                $this->traverseTree( $node[ 'hash' ], $path . '/' . $node[ 'filename' ] );
            }
        }

    }
}
