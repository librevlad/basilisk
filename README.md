# Basilisk

Version Control System Penetration Testing Toolkit

## Usage (as binary)

You can install the package via composer:

```bash
composer global require librevlad/basilisk
```

## Usage (as library)

```bash
composer require librevlad/basilisk
```

### Finder

```php

$finder = new Finder( $urls, $threads );
$results = $finder->find( function ( $request ) { 

  echo "Found git on ".$request->url();

});

var_dump( $results['success'] );


```

### Dumper

```php

$dumper = new Dumper( $url, $dest, $threads );
$dumper->dump();

```

### Extractor

```php

$extractor = new Extractor( $src, $dest = null );
$extractor->extract();

```

## Testing

```bash
composer test
```

## License

The MIT License (MIT).
