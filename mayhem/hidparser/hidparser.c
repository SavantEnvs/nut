/* libFuzzer harness for NUT's USB HID report-descriptor parser (drivers/hidparser.c)
 * and the report field accessors GetValue/SetValue that every usbhid-ups mapping uses. */
#include "config.h"
#include "hidparser.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	HIDDesc_t *desc;
	unsigned char *desc_buf, *report;
	size_t i, bytes;

	if (size < 1 || size > REPORT_DSC_SIZE)
		return -1;

	desc_buf = (unsigned char *)malloc(size);
	if (!desc_buf)
		return -1;
	memcpy(desc_buf, data, size);

	desc = Parse_ReportDesc(desc_buf, size);
	free(desc_buf);

	if (!desc)
		return -1;

	for (i = 0; i < desc->nitems; i++) {
		HIDData_t *item = &desc->item[i];
		HIDData_t *found;
		long value = 0, back = 0;

		found = FindObject_with_ID(desc, item->ReportID, item->Offset, item->Type);
		if (found) {
			FindObject_with_Path(desc, &item->Path, item->Type);
			FindObject(desc, item);
		}

		/* the report buffer is replen bytes plus the ID byte, as usbhid-ups allocates it */
		bytes = desc->replen[item->ReportID] + 1;
		report = (unsigned char *)calloc(bytes, 1);
		if (!report)
			continue;

		/* both accessors write/read within the field's own bit range */
		if (((size_t)item->Offset + item->Size + 7) / 8 + 1 <= bytes && item->Size <= 32) {
			SetValue(item, report, (long)(0x5a5a5a5a ^ (unsigned long)i));
			GetValue(report, item, &value);
			SetValue(item, report, value);
			GetValue(report, item, &back);
		}
		free(report);
	}

	Free_ReportDesc(desc);
	return 0;
}
