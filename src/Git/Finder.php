<?php


namespace Librevlad\Basilisk\Git;


use Librevlad\Basilisk\OutputOnCommand;
use ScrapeKit\ScrapeKit\Common\UserAgent;
use ScrapeKit\ScrapeKit\Http\Requests\Request;

class Finder {
    use OutputOnCommand;

    /**
     * @var array
     */
    public $urls;
    /**
     * @var int
     */
    public $threads;

    public $succeeded = [];
    public $failed = [];

    public function __construct( array $urls, $threads = 60 ) {

        $this->urls    = $urls;
        $this->threads = $threads;
    }

    public function find( $onSuccess = null, $onFail = null ) {

        $this->line( 'Processing ' . count( $this->urls ) . ' domains on ' . $this->threads . ' threads' );

        if ( $onSuccess === null ) {
            $onSuccess = function () {
            };
        }

        if ( $onFail === null ) {
            $onFail = function () {
            };
        }

        $client = scrapekit()->http()->threads( $this->threads );
        foreach ( $this->urls as $url ) {

            $req = Request::make( fix_url( $url . '/.git/HEAD' ) )
                          ->timeouts( 8, 10, 12 )
                          ->userAgent( UserAgent::chrome() )
                          ->validator( function ( Request $request ) {
                              $valid = $request->response() && $request->response()->body()
                                       && ( strpos( $request->response()->body(), "ref: refs" ) !== false );

                              return $valid;
                          } )
                          ->onSuccess( $onSuccess )
                          ->onFail( $onFail )
                          ->onFail( function () use ( $url ) {
                              $this->failed[] = $url;
                          } )
                          ->onSuccess( function () use ( $url ) {
                              $this->succeeded[] = $url;
                              $this->info( $url );
                          } )
                /**//**/
            ;
            $client->addRequest( $req );
        }

        $client->run();

        return [
            'success' => $this->succeeded,
            'fail'    => $this->failed,
        ];
    }
}
