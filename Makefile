.PHONY: test experiments check clean

test:
	PYTHONPATH=simulator python -m unittest discover -s simulator/tests -v

experiments:
	./tools/run_experiments.sh

check:
	./tools/check_repo.sh

clean:
	rm -rf build dist reports/*.json
