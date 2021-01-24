q_create_function = r'''
mutation CreateFunction($name: String!, $sourceCode: String, $pseudoCode: String, $sourceFile: String, $sourceLine: Int,
                        $packageName: String,
                        $binaryFileName: String, $binarySha256: String, $fileoffset: Int, $bytes: String, $platform: String,
                        $feature: String!) {
    createFunction(input: {
        name: $name,
        representationInfo: {type: IR_IDA, version: 2, info: $feature},
        binaryInfo: {filename: $binaryFileName, sha256: $binarySha256, fileoffset: $fileoffset,
                     bytes: $bytes, platform: $platform},
        sourceCodeInfo: {code: $sourceCode, pseudocode: $pseudoCode, packagename: $packageName,
                         filename: $sourceFile, linenumber: $sourceLine}
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
            code
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

q_saveto_function_set_members = r'''
mutation saveToFunctionSetMembers($setID: ID!, $functionIds: [ID!]!){
    saveToFunctionSetMembers(input: {functionSetID: $setID, functionIDs: $functionIds}){
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
            nodes {
                id
            }
        }
    }
}
'''

q_query_created_function_set = r'''
query QueryCreatedFuncitonSet {
  viewer {
    createdFunctionSets {
      nodes {
        id
      }
    }
  }
}
'''

q_search_func_similarity = r'''
query SearchFuncSimilarity($funcId: ID!, $topk: Int!) {
    retrieveList {
        searchByID(id: $funcId, topK: $topk) {
            score
            function {
                id
                name
                sourceCodeInfo {
                    code
                    pseudocode
                    filename
                    linenumber
                    packagename
                }
                binaryInfo {
                    filename
                    platform
                }
            }
        }
    }
}
'''

q_search_func_similarity_by_feature = r'''
query SearchFuncSimilarity($feature: String!, $topk: Int!) {
  retrieveList {
    searchByRepresentation(topK: $topk, representationInfo: {type: IR_IDA, version: 2, info: $feature}) {
      score
      function {
        id
        name
        sourceCodeInfo {
          code
          pseudocode
          filename
          linenumber
          packagename
        }
        binaryInfo {
          filename
          fileoffset
          platform
          sha256
        }
      }
    }
  }
}
'''

q_clear_retrieve_list = r'''
mutation ClearRetrieveList {
  clearRetrieveList {
    clientMutationId
  }
}
'''

q_insert_retrieve_list = r'''
mutation AddToRetrieveList($functionid: [ID!], $functionsetid: [ID!]) {
  addToRetrieveList(input: {functionId: $functionid, functionSetId: $functionsetid}) {
    clientMutationId
  }
}
'''


q_retrieve_list_count = r'''
query RetrieveList($offset: Int!, $limit: Int!, $isFunction: Boolean!) {
  retrieveList {
    functions(offset: $offset, limit: $limit) @include(if: $isFunction) {
      totalCount
    }
  }
}
'''
