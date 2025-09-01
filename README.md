# python-traceback-obfuscator
This project combines two ideas: Nuitka’s encrypted tracebacks and PyArmor’s RFT mode into a single workflow: you can obfuscate symbol names and optionally emit encrypted exception tracebacks at runtime, then later decrypt and de‑obfuscate those tracebacks offline when you have the key and tracelog.
