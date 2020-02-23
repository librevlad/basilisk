<?php

function prepareDir( $pth ) {
    if ( ! file_exists( dirname( $pth ) ) ) {
        mkdir( dirname( $pth ), 0777, true );
    }
}
