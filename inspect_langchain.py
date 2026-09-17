from langchain.agents import create_agent
from langchain.agents.middleware import wrap_tool_call
import inspect


print("create_agent:")
print(inspect.signature(create_agent))

print("\nwrap_tool_call:")
print(inspect.signature(wrap_tool_call))