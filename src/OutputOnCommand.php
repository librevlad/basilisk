<?php


namespace Librevlad\Basilisk;

trait OutputOnCommand {

    protected $command;

    /**
     * @param mixed $command
     *
     * @return $this
     */
    public function setCommand( $command ) {
        $this->command = $command;

        return $this;
    }

    /**
     * Write a string as information output.
     *
     * @param string $string
     * @param int|string|null $verbosity
     *
     * @return void
     */
    public function info( $string, $verbosity = null ) {
        $this->line( $string, 'info', $verbosity );
    }

    /**
     * Write a string as standard output.
     *
     * @param string $string
     * @param string|null $style
     * @param int|string|null $verbosity
     *
     * @return void
     */
    public function line( $string, $style = null, $verbosity = null ) {

        if ( $this->command ) {
            return $this->command->line( '[' . date( 'H:i:s' ) . '] ' . $string, $style, $verbosity );
        }

    }

    /**
     * Write a string as comment output.
     *
     * @param string $string
     * @param int|string|null $verbosity
     *
     * @return void
     */
    public function comment( $string, $verbosity = null ) {
        $this->line( $string, 'comment', $verbosity );
    }

    /**
     * Write a string as error output.
     *
     * @param string $string
     * @param int|string|null $verbosity
     *
     * @return void
     */
    public function error( $string, $verbosity = null ) {
        $this->line( $string, 'error', $verbosity );
    }

    /**
     * Write a string as warning output.
     *
     * @param string $string
     * @param int|string|null $verbosity
     *
     * @return void
     */
    public function warn( $string, $verbosity = null ) {
        if ( $this->command ) {
            $this->command->warn( '[' . date( 'H:i:s' ) . '] ' . $string, $verbosity );
        }
    }

    /**
     * Write a string in an alert box.
     *
     * @param string $string
     *
     * @return void
     */
    public function alert( $string ) {
        $length = strlen( strip_tags( $string ) ) + 12;

        $this->comment( str_repeat( '*', $length ) );
        $this->comment( '*     ' . $string . '     *' );
        $this->comment( str_repeat( '*', $length ) );

        $this->line( ' ' );
    }

}
