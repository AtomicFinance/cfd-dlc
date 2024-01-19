build:
  ./scripts/build.sh

test:
  ./scripts/build.sh
  ./scripts/run_cfddlc_tests.sh

lint:
  ./scripts/lint.sh
