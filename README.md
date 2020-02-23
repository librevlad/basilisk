<pre>
 ____            _ _ _     _    
|  _ \          (_) (_)   | |   
| |_) | __ _ ___ _| |_ ___| | __
|  _ < / _` / __| | | / __| |/ /
| |_) | (_| \__ \ | | \__ \   < 
|____/ \__,_|___/_|_|_|___/_|\_\
</pre>
Basilisk
============                                

Version Control System Penetration Testing Toolkit

## Usage (as binary)

You can install the package via composer:

```bash
composer global require librevlad/basilisk
```

Add `~/.config/composer/vendor/bin/` to your `PATH`

Find repositories:
```bash
basilisk git:find -o gits.txt --threads=10 urls.txt
```
Fetch repository:
```bash
basilisk git:dump -t 10 http://example.com ./examplecom
```
Extract repository:
```bash
basilisk git:extract ./examplecom
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
