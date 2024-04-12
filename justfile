build:
  ./scripts/build.sh

test:
  ./scripts/build.sh
  ./scripts/run_cfddlc_tests.sh

lint:
  ./scripts/lint.sh

build_ios:
  ./scripts/build_ios.sh

build_sim:
  ./scripts/build_sim.sh

ecmult:
  ./scripts/ecmult.sh

merge:
  ./scripts/merge.sh
