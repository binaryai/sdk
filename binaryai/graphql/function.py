q_create_function = '''
mutation CreateFunction($name: String!, $sourceCode: String, $sourceFile: String, $sourceLine: Int,
                        $language: String, $feature: String!, $functionSetId: ID){
    createFunction(input: {name: $name, sourceCode: $sourceCode, sourceFile: $sourceFile, sourceLine: $sourceLine,
                            language: $language, feature: $feature, functionSetId: $functionSetId}){
        function {
            id
        }
    }
}
'''

q_query_function = '''
query QueryFunction($funcId: ID!){
    function(id: $funcId){
        id
        name
        sourceCode
        sourceFile
        sourceLine
        language
    }
}
'''

q_create_function_set = '''
mutation CreateFunctionSet($functionIds: [ID!]){
    createFunctionSet(input: {functionIds: $functionIds}){
        functionSet{
            id
        }
    }
}
'''

q_query_function_set = '''
query QueryFuncitonSet($funcSetId: ID!){
    functionSet(id: $funcSetId){
        id
        functions {
            id
        }
    }
}
'''

q_search_func_similarity = '''
query SearchFuncSimilarity($funcId: ID!, $setId: [ID!], $topk: Int!){
    function(id: $funcId){
        similarity(functionSetIds: $setId, topK: $topk){
            score
            function{
                id
                name
                sourceCode
                sourceFile
                sourceLine
                language
            }
        }
    }
}
'''
