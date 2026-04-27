// Copyright 2026 The NetKAT authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_
#define GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_

#include <vector>

#include "absl/status/status.h"
#include "absl/types/source_location.h"
#include "netkat/frontend.h"
#include "netkat/table.h"

namespace netkat {

struct Rule {
  int priority;
  Predicate match;
  Policy action;
  absl::SourceLocation loc = absl::SourceLocation::current();
};

// A helper class for modifying an existing NetkatTable using a fluent
// interface. Modifications are applied atomically: if any rule fails to be
// installed (e.g., due to a constraint violation), the underlying table remains
// completely unmodified.
class NetkatTableBuilder {
 public:
  // Logs the current rules in the NetkatTableBuilder to LOG(INFO).
  NetkatTableBuilder& LogRules();

  // Adds a rule to be inserted into the table at the given priority.
  NetkatTableBuilder& AddRule(const Rule& rule);

  // Moves all buffered rules into the table atomically. Returns an error
  // with the source location of the caller if any rule cannot be successfully
  // added. If any rule fails to be installed (e.g., due to a constraint
  // violation), the underlying table remains completely unmodified.
  absl::Status InstallRules();

 private:
  friend class NetkatTable;

  explicit NetkatTableBuilder(NetkatTable* table);

  std::vector<Rule> rules_;
  NetkatTable* table_;
};

}  // namespace netkat

#endif  // GOOGLE_NETKAT_NETKAT_TABLE_BUILDER_H_
