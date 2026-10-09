/* Deliberately outside the accepted classic fixture profile. */
_Thread_local int glue_tlv_value = 7;

int glue_tlv_read(void) {
    return glue_tlv_value;
}
