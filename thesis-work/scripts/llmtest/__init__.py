"""LLM-driven OpenSSL unit test generation.

Stdlib only -- no third-party dependencies.

Modules:
  paths     -- repo/thesis directory resolution
  context   -- assemble the prompt bundle sent to the model
  stub      -- scaffold a test .c skeleton, splice model output into it
  backends  -- local Ollama and remote OpenAI-compatible endpoints
  cli       -- argparse entry point
"""
