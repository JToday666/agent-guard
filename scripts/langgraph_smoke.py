from typing_extensions import TypedDict

from langgraph.graph import END, START, StateGraph


class SmokeState(TypedDict):
    value: str


def echo(state: SmokeState) -> SmokeState:
    return {"value": f"{state['value']} ok"}


graph = StateGraph(SmokeState)
graph.add_node("echo", echo)
graph.add_edge(START, "echo")
graph.add_edge("echo", END)

app = graph.compile()
print(app.invoke({"value": "langgraph"}))
