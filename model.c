
typedef void* va_list;

int asprintf(char **strp, const char *fmt, ...)
{
    char ch1;
    int success;
    unsigned int total_bytes_printed;

    /* fmt must be NUL terminated, and reasonably bounded */
    __coverity_string_null_sink__((void*)fmt);
    __coverity_string_size_sink__((void*)fmt);

    /* Reads fmt */
    ch1 = *fmt;

    if ( success )
    {
        /* Allocates a string.  Exact size is not calculable */
        char *str = __coverity_alloc_nosize__();

        /* Should be freed with free() */
        __coverity_mark_as_afm_allocated__(str, AFM_free);

        /* Returns memory via first parameter */
        *strp = str;

        /* Writes to all of the allocated string */
        __coverity_writeall__(str);

        /* Returns a positive number of bytes printed on success */
        return total_bytes_printed;
    }
    else
    {
        /* Return -1 on failure */
        return -1;
    }
}

int vasprintf(char **strp, const char *fmt, va_list ap)
{
    char ch1;
    int success;
    unsigned int total_bytes_printed;

    /* fmt must be NUL terminated, and reasonably bounded */
    __coverity_string_null_sink__((void*)fmt);
    __coverity_string_size_sink__((void*)fmt);

    /* Reads fmt */
    ch1 = *fmt;

    /* Reads ap */
    ch1 = *(char*)ap;

    if ( success )
    {
        /* Allocates a string.  Exact size is not calculable */
        char *str = __coverity_alloc_nosize__();

        /* Should be freed with free() */
        __coverity_mark_as_afm_allocated__(str, AFM_free);

        /* Returns memory via first parameter */
        *strp = str;

        /* Writes to all of the allocated string */
        __coverity_writeall__(str);

        /* Returns a positive number of bytes printed on success */
        return total_bytes_printed;
    }
    else
    {
        /* Return -1 on failure */
        return -1;
    }
}
