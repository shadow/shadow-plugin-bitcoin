# - Check for the presence of LIBDB
#
# The following variables are set when LIBDB is found:
#  HAVE_LIBDB       = Set to true, if all components of LIBDB
#                          have been found.
#  LIBDB_INCLUDES   = Include path for the header files of LIBDB
#  LIBDB_LIBRARIES  = Link these to use LIBDB

## -----------------------------------------------------------------------------
## Check for the header files

find_path (LIBDB_INCLUDES db.h
  PATHS /usr/local/include /usr/include /include /sw/include
  PATH_SUFFIXES libdb4/
  )

## -----------------------------------------------------------------------------
## Check for the library

find_library (LIBDB_LIBRARIES db-4
  PATHS /usr/local/lib /usr/lib /lib /sw/lib /usr/lib64 /usr/lib/x86_64-linux-gnu/
  )

## -----------------------------------------------------------------------------
## Actions taken when all components have been found

if (LIBDB_INCLUDES AND LIBDB_LIBRARIES)
  set (HAVE_LIBDB TRUE)
else (LIBDB_INCLUDES AND LIBDB_LIBRARIES)
  if (NOT LIBDB_FIND_QUIETLY)
    if (NOT LIBDB_INCLUDES)
      message (STATUS "Unable to find LIBDB header files!")
    endif (NOT LIBDB_INCLUDES)
    if (NOT LIBDB_LIBRARIES)
      message (STATUS "Unable to find LIBDB library files!")
    endif (NOT LIBDB_LIBRARIES)
  endif (NOT LIBDB_FIND_QUIETLY)
endif (LIBDB_INCLUDES AND LIBDB_LIBRARIES)

if (HAVE_LIBDB)
  if (NOT LIBDB_FIND_QUIETLY)
    message (STATUS "Found components for LIBDB")
    message (STATUS "LIBDB_INCLUDES = ${LIBDB_INCLUDES}")
    message (STATUS "LIBDB_LIBRARIES = ${LIBDB_LIBRARIES}")
  endif (NOT LIBDB_FIND_QUIETLY)
else (HAVE_LIBDB)
  if (LIBDB_FIND_REQUIRED)
    message (FATAL_ERROR "Could not find LIBDB!")
  endif (LIBDB_FIND_REQUIRED)
endif (HAVE_LIBDB)

mark_as_advanced (
  HAVE_LIBDB
  LIBDB_LIBRARIES
  LIBDB_INCLUDES
  )
