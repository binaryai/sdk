q_create_function = r'''
mutation CreateFunction($name: String!, $sourceCode: String, $sourceFile: String, $sourceLine: Int,
                        $binaryFileName: String, $platform: String, $feature: String!) {
    createFunction(input: {
        name: $name, 
        representationInfo: {type: IR_IDA, version: 1, graph: $feature}, 
        binaryInfo: {filename: $binaryFileName, platform: $platform}, 
        sourceCodeInfo: {pseudocode: $sourceCode, filename: $sourceFile, linenumber: $sourceLine}
    }) {
        function {
            id
        }
    }
}
'''

q_query_function = r'''
query QueryFunction($funcId: ID!){
    function(id: $funcId){
        id
        name
        sourceCodeInfo {
            pseudocode
            filename
            linenumber
        }
        binaryInfo {
            filename
            platform
        }
    }
}
'''

q_create_function_set = r'''
mutation CreateFunctionSet($name: String!, $description: String){
    createFunctionSet(input: {name: $name, description: $description}){
        functionSet{
            id
            name
            description
        }
    }
}
'''

q_insert_function_set_members = r'''
mutation InsertFunctionSetMembers($setID: ID!, $functionIds: [ID!]!){
    insertFunctionSetMembers(input: {functionSetID: $setID, functionIDs: $functionIds}){
        functionSet{
            id
        }
    }
}
'''

q_query_function_set = r'''
query QueryFuncitonSet($funcSetId: ID!){
    functionSet(id: $funcSetId){
        id
        functions {
            id
        }
    }
}
'''

q_search_func_similarity = r'''
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
