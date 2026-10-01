// Platforms without a socket table reader.
#include "procs/Owners.h"

namespace pm {

bool readSystemSockets(SocketTable&, std::string& error) {
    error = "app names aren't supported on this system";
    return false;
}

}  // namespace pm
