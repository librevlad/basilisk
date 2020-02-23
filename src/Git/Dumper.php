<?php

namespace Librevlad\Basilisk\Git;


use Librevlad\Basilisk\OutputOnCommand;
use ScrapeKit\ScrapeKit\Http\Requests\Request;

class Dumper {
    use OutputOnCommand;

    /**
     * @var string
     */
    public $url;
    /**
     * @var string
     */
    public $path;
    /**
     * @var int
     */
    public $threads = 3;
    /**
     * @var array
     */
    protected $queue = [];

    /**
     * @var Repository
     */
    protected $repo;

    protected $processedHashes = [];

    public function __construct( $url, $path, $threads = 3 ) {
        $this->url     = $url;
        $this->path    = $path;
        $this->threads = $threads;

        $this->repo = new Repository( $path );

    }

    public function dump() {
        $files = require( __DIR__ . '/../../config/config.php' );
        $files = $files[ 'git' ][ 'static_files' ];

        return $this->downloadFiles( $files );
    }

    protected function downloadFiles( array $files ) {
        if ( ! count( $files ) ) {
            return;
        }

        $this->comment( 'Using ' . $this->threads . ' threads' );
        $client = scrapekit()->http()->threads( $this->threads );

        foreach ( $files as $file ) {
            //            if ( file_exists( $this->path . '/.git/' . $file ) ) {
            //                $this->processFile( $file, file_get_contents( $this->path . '/.git/' . $file ) );
            //                continue;
            //            }
            $client->addRequest(
                Request::make( $this->url . '/.git/' . $file )
                       ->cache()
                       ->onSuccess( function ( Request $request ) use ( $file ) {
                           $this->info( $file );
                           $this->saveFile( $file, $request->response()->body() );
                           $this->processFile( $file, $request->response()->body() );
                       } )
                       ->onFail( function ( Request $request ) use ( $file ) {
                           $this->error( $file );
                           $this->processedHashes [ $file ] = 1;
                       } )
            );

        }

        $client->run();

        $this->queue = array_unique( array_diff( $this->queue, array_keys( $this->processedHashes ) ) );

        $this->downloadFiles( $this->queue );
        $this->queue = [];
    }

    public function processFile( $fn, $content ) {
        if ( isset( $this->processedHashes[ $fn ] ) ) {
            return;
        }

        $objects = [];
        if ( $hash = $this->repo->object_hash_from_filename( $fn ) ) {
            // it's an object - grab other objects hashes and add them to the queue
            foreach ( Parser::objects( $this->repo->catFileContents( $hash ) ) as $o ) {
                $objects[] = $this->repo->filename_from_object_hash( $o );
            }
        }

        // Add everthing we can find in text - objects
        foreach ( Parser::objects( $content ) as $o ) {
            $objects[] = $this->repo->filename_from_object_hash( $o );
        }
        // Add everthing we can find in text - packs
        foreach ( Parser::packs( $content ) as $o ) {
            $objects[] = 'objects/pack/' . $o . '.pack';
            $objects[] = 'objects/pack/' . $o . '.idx';
        }

        foreach ( $objects as &$o ) {
            if ( isset( $this->processedHashes[ $o ] ) ) {
                unset( $o );
            }
        }

        $this->queue                   = array_merge( $this->queue, $objects );
        $this->processedHashes [ $fn ] = 1;
    }

    /*
     * Utility Methods
     */

    protected function saveFile( $fn, $text ) {
        $pth = $this->path . '/.git/' . $fn;
        prepareDir( $pth );
        file_put_contents( $pth, $text );
    }
}
