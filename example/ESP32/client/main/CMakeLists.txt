set(src_dirs 
    "."
    "../../common"
    "../../common/nanopb"
    "../../../../apt-sdk"
    )

set(include_dirs 
    "."
    "../../common"
    "../../common/nanopb"
    "../../../../apt-sdk"
    )

idf_component_register( 
                        SRC_DIRS "${src_dirs}"
                        EXCLUDE_SRCS "${exc_sirs}"
                       INCLUDE_DIRS "${include_dirs}"
                       )

