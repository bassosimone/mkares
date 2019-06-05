# Measurement Kit UDP-based DNS client

[![GitHub license](https://img.shields.io/github/license/measurement-kit/mkudns.svg)](https://raw.githubusercontent.com/measurement-kit/mkudns/master/LICENSE) [![Github Releases](https://img.shields.io/github/release/measurement-kit/mkudns.svg)](https://github.com/measurement-kit/mkudns/releases) [![Build Status](https://img.shields.io/travis/measurement-kit/mkudns/master.svg?label=travis)](https://travis-ci.org/measurement-kit/mkudns) [![codecov](https://codecov.io/gh/measurement-kit/mkudns/branch/master/graph/badge.svg)](https://codecov.io/gh/measurement-kit/mkudns) [![Build status](https://img.shields.io/appveyor/ci/bassosimone/mkudns/master.svg?label=appveyor)](https://ci.appveyor.com/project/bassosimone/mkudns/branch/master)

Experimental library to perform UDP-based DNS queries in MK.

⚠️⚠️⚠️⚠️⚠️⚠️⚠️: We're going to archive this. We'll use a Go engine to implement this
functionality in OONI. So, this experiment can now go to the attic.

## Regenerating build files

Possibly edit `MKBuild.yaml`, then run:

```
go get -v github.com/measurement-kit/mkbuild
mkbuild
```

## Building

```
mkdir build
cd build
cmake -GNinja ..
cmake --build .
ctest -a -j8 --output-on-failure
```

## Testing with docker

```
./docker.sh <build-type>
```
