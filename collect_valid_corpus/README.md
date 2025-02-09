## Generate Corpus

This project generates seed corpus zip files from Ethereum consensus spec SSZ files. It uses Go generics to collect valid SSZ data and compress them into zip files. The project also uses go generate to automatically create type-specific seed corpus functions.

----

### Project Structure

```bash
collect_valid_corpus/
├── consensus-spec-tests/         # Directory containing SSZ test corpus data.
├── corpus_generator.go           # Generator script (ignored in build; run via go generate).
├── corpus_generated.go           # Automatically generated seed corpus functions.
└── generate_corpus.go            # Core functionality (generic corpus collection) and main() function.
```
----

### Usage



#### 1. Run Go Generate

In the project directory, run:

```bash
go generate corpus_generator.go 
```

This command executes the generator script (`corpus_generator.go`) to automatically create or update the file `corpus_generated.go` with type-specific functions.

#### 2. Build the Executable

Build the project by running:

```bash
go build -o gen_corpus generate_corpus.go corpus_generated.go make_all.go 
```


