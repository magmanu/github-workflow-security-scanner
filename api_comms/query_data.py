import pydash as _

def return_query(query_type, name, branch="", after=None):
    if query_type == "repository":
        owner, name = _.take(name.split("/"), 2)

        return f"""query {{
                    repository(owner: "{owner}",name: "{name}") {{
                        nameWithOwner
                        object(expression: "{branch}:.github/workflows/") {{
                            ... on Tree {{
                                entries {{
                                    name
                                    lineCount
                                    object {{
                                        ... on Blob {{
                                            text
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }}
        }}"""
    if query_type == "action":
        owner, name = name.split("/")
        return f"""query {{
                    repository(owner: "{owner}",name: "{name}") {{
                        nameWithOwner
                        yml: object(expression: "HEAD:action.yml") {{
                            ... on Blob {{
                                text
                                byteSize
                            }}
                        }}
                        yaml: object(expression: "HEAD:action.yaml") {{
                            ... on Blob {{
                                text
                                byteSize
                            }}
                        }}
                    }}
        }}"""
    else:
        after_query = f',after:"{after}"' if after else ""
        return f"""query {{
        {query_type}(login:"{name}"){{
            repositories(first:100 {after_query}){{
            edges{{
                node{{
                nameWithOwner,
                object(expression: "{branch}:.github/workflows/") {{
                    ... on Tree {{
                    entries {{
                        name
                        lineCount
                        object {{
                                ... on Blob {{
                            text
                        }}
                        }}
                    }}
                    }}
                }}
                }}
            }}
            pageInfo {{
                startCursor
                hasNextPage
                endCursor
            }}
            }}
        }}
        }}"""


def validation_query(username, guess_type):
    return f"""query {{ 
                {guess_type}(login:"{username}"){{
                    repositories(first:1){{
                        edges{{
                            node{{
                                nameWithOwner
                            }}
                        }}
                    }}
                }}
            }}"""
