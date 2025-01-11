#!/bin/bash -eu
#
# oss-fuzz.sh : Builds multiple fuzzers, each in its own subfolder (static, dynamic, etc.)

# Adjust or remove coverage pkg logic as needed
#!/bin/bash -eu

coverpkg="github.com/KindKillerwhale/sszfuzzer/..."
SANITIZER="address"
CXX="clang++"
CXXFLAGS="-O1 -g"
LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
OUT="./"
CC=clang


function coverbuild {
  path=$1
  function=$2
  fuzzer=$3
  tags=""

  if [[ $#  -eq 4 ]]; then
    tags="-tags $4"
  fi
  cd $path
  fuzzed_package=`pwd | rev | cut -d'/' -f 1 | rev`
  cp $GOPATH/ossfuzz_coverage_runner.go ./"${function,,}"_test.go
  sed -i -e 's/FuzzFunction/'$function'/' ./"${function,,}"_test.go
  sed -i -e 's/mypackagebeingfuzzed/'$fuzzed_package'/' ./"${function,,}"_test.go
  sed -i -e 's/TestFuzzCorpus/Test'$function'Corpus/' ./"${function,,}"_test.go

cat << DOG > $OUT/$fuzzer
#/bin/sh

  cd $OUT/$path
  go test -run Test${function}Corpus -v $tags -coverprofile \$1 -coverpkg $coverpkg

DOG

  chmod +x $OUT/$fuzzer
  #echo "Built script $OUT/$fuzzer"
  #cat $OUT/$fuzzer
  cd -
}


function compile_fuzzer() {
  package=$1
  function=$2
  fuzzer=$3
  file=$4

  path=$GOPATH/src/$package

  echo "Building $fuzzer in $path"
  cd $path

  go mod tidy
  go get github.com/holiman/gofuzz-shim/testing

  if [[ $SANITIZER == *coverage* ]]; then
    coverbuild $path $function $fuzzer $coverpkg
  else
    gofuzz-shim --func $function --package $package -f $file -o $fuzzer.a
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
  fi
  cd -
}

go install github.com/holiman/gofuzz-shim@latest
repo=$GOPATH/src/github.com/KindKillerwhale/sszfuzzer

compile_fuzzer github.com/KindKillerwhale/sszfuzzer/consensus_fuzz \
  FuzzConsensusSpecsAggregateAndProof \
  fuzz_consensus_specs_aggregate_and_proof \
  "$repo/consensus_fuzz/fuzz_consensus_specs.go"
