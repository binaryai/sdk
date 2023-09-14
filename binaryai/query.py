#!/usr/bin/env python3
# -*- coding: utf-8 -*-

QUERY_SHA256 = """query Sha256($md5: String!) {
  file: fileByHash(input: {md5: $md5}) {
    sha256
  }
}
"""

QUERY_FILENAMES = """query Filename($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    name
  }
}
"""

QUERY_MIME_TYPE = """query MIMEType($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    mimeType
  }
}
"""

QUERY_FILE_SIZE = """query MIMEType($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    size
  }
}
"""

QUERY_CVE_NAME = """query CVEName($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    scainfo {
      cves {
        name
      }
    }
  }
}
"""

QUERY_LICENSE_SHORT_NAME = """query LicenseShortName($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    scainfo {
      license
    }
  }
}
"""

QUERY_LICENSE = """query License($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    scainfo {
      licenselist {
        checkreason
        content
        extra
        fullName
        pass
        risk
        shortName
        source
        url
        tags {
          permission {
            tagName
            description
          }
          condition {
            tagName
            description
          }
          forbidden {
            tagName
            description
          }
        }
      }
    }
  }
}
"""

QUERY_ASCII_STRING = """query ASCIIString($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    executable {
      ... on COFFInfo {
        asciiStrings
      }
      ... on ELFInfo {
        asciiStrings
      }
      ... on MachoInfo {
        asciiStrings
      }
      ... on PEInfo {
        asciiStrings
      }
    }
  }
}
"""

QUERY_SCA = """query SCA($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    scainfo {
      name
      version
      description
      sourceCodeURL
      summary
    }
  }
}
"""

QUERY_OVERVIEW = """query Overview($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    decompileResult {
      basicInfo {
        fileType
        machine
        platform
        endian
        loader
        entryPoint
        baseAddress
      }
    }
  }
}
"""

QUERY_DOWNLOAD_LINK = """query DownloadLink($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    downloadLink
  }
}
"""

QUERY_CHECK_STATE = """query CheckState($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    smartBinaryStatus : analyzeStatus(analyzer: SmartBinary) {
      status
    }
    smartBeatStatus : analyzeStatus(analyzer: SmartBeat) {
      status
    }
    text {
      content           # trigger smartBinary
    }
    decompileResult {
      basicInfo {
        fileType        # trigger smartBeat
      }
    }
  }
}
"""

QUERY_FUNCTION_LIST = """query FunctionList($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    decompileResult {
      functions {
        offset
      }
    }
  }
}
"""

QUERY_FUNCTION_INFO = """query FunctionInfo($sha256: String!, $offset: BigInt!, $withEmbedding: Boolean!) {
    file: fileByHash(input: {sha256: $sha256}) {
        decompileResult {
            function(offset: $offset) {
                offset
                name
                embedding @include(if: $withEmbedding) {
                    vector
                    version
                }
                pseudoCode {
                    code
                }
            }
        }
    }
}
"""

QUERY_FUNCTIONS_INFO = """query FunctionsInfo($sha256: String!, $offset: [BigInt!], $withEmbedding: Boolean!) {
    file: fileByHash(input: {sha256: $sha256}) {
        decompileResult {
            functions(offset: $offset) {
                offset
                name
                embedding @include(if: $withEmbedding) {
                    vector
                    version
                }
                pseudoCode {
                    code
                }
            }
        }
    }
}
"""

QUERY_FUNCTION_MATCH = """query FunctionMatch($sha256: String!, $offset: BigInt!) {
  file: fileByHash(input: {sha256: $sha256}) {
    decompileResult {
      function(offset: $offset) {
        match(topK: 10) {
          score
          function {
            code
          }
        }
      }
    }
  }
}
"""

QUERY_COMPRESSED_FILE = """query CompressedFile($sha256: String!) {
  file: fileByHash(input: {sha256: $sha256}) {
    decompressed {
      ... on CompressedFile {
        path
        sha256
      }
    }
  }
}
"""

MUTATION_REANALYZE = """mutation Reanalyze($input: ReanalyzeInput!) {
  reanalyze(input: $input) {
    noopReason
    file {
      analyzeStatus {
        status
      }
    }
  }
}"""

MUTATION_CREATE_TICKET = """mutation CheckOrUpload($input: CreateUploadTicketInput!) {
  createUploadTicket(input: $input) {
    __typename
    ... on File {
      sha256
    }
    ... on UploadTicket {
      ticketID
      url
      requestHeaders {
        key
        value
      }
    }
    ... on OwnershipTicket {
      ticketID
      secretPrepend
      secretAppend
    }
  }
}
"""

MUTATON_CREATE_FILE = """mutation CreateFile($input: CreateFileInput!) {
  createFile(input: $input) {
    sha256
    md5
    name
    size
    mimeType
    createTime
  }
}
"""
