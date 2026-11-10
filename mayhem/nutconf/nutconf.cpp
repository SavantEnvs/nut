/* libFuzzer harness for libnutconf, NUT's C++ configuration-file parsers/serialisers
 * (nut.conf, upsmon.conf, upsd.conf, ups.conf, upsd.users, and the client auth file). */
#include "config.h"
#include "nutconf.hpp"
#include "nutstream.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <string>

static const size_t MAX_SIZE = 65536;

template <typename Conf>
static void roundtrip(const std::string &text)
{
	Conf conf;
	nut::NutMemory out;
	std::string dumped;

	conf.parseFromString(text);
	if (conf.writeTo(out))
		out.getString(dumped);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2 || size > MAX_SIZE)
		return -1;

	const std::string text(reinterpret_cast<const char *>(data + 1), size - 1);

	try {
		switch (data[0] % 6) {
		case 0: roundtrip<nut::NutConfiguration>(text); break;
		case 1: roundtrip<nut::UpsmonConfiguration>(text); break;
		case 2: roundtrip<nut::UpsdConfiguration>(text); break;
		case 3: roundtrip<nut::UpsConfiguration>(text); break;
		case 4: roundtrip<nut::UpsdUsersConfiguration>(text); break;
		default: roundtrip<nut::NutAuthConfiguration>(text); break;
		}
	} catch (const std::exception &) {
		return -1;
	}

	return 0;
}
