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

#include "netkat/table_builder.h"

#include <string>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/types/source_location.h"
#include "gutil/proto.h"
#include "netkat/table.h"

namespace netkat {

NetkatTableBuilder NetkatTable::TableBuilder() & {
  return NetkatTableBuilder(this);
}

NetkatTableBuilder::NetkatTableBuilder(NetkatTable* table) : table_(table) {}

NetkatTableBuilder& NetkatTableBuilder::LogRules() {
  LOG(INFO)
      << "Rules in the table builder: \n"
      << absl::StrJoin(rules_, "\n", [](std::string* out, const auto& rule) {
           absl::StrAppend(
               out, "priority: ", rule.priority,
               "\nmatch: ", gutil::PrintTextProto(rule.match.GetProto()),
               "action: ", gutil::PrintTextProto(rule.action.GetProto()));
         });
  return *this;
}

NetkatTableBuilder& NetkatTableBuilder::AddRule(const Rule& rule) {
  rules_.emplace_back(std::move(rule));
  return *this;
}

absl::Status NetkatTableBuilder::InstallRules() {
  if (table_ == nullptr) {
    return absl::InternalError("table is null.");
  }
  NetkatTable temp_table(*table_);
  for (Rule& rule : rules_) {
    absl::Status status = temp_table.AddRule(
        rule.priority, std::move(rule.match), std::move(rule.action));
    if (!status.ok()) {
      return absl::Status(
          status.code(),
          absl::StrCat(rule.loc.file_name(), ":", rule.loc.line(),
                       ": Failed to install table rule: ", status.message()));
    }
  }
  *table_ = std::move(temp_table);
  return absl::OkStatus();
}

}  // namespace netkat
