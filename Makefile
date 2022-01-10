python=/usr/bin/env python3


test:
	echo && PYTHONPATH="${PYTHONPATH}:handshake" $(python) -m unittest discover -s tests -v
