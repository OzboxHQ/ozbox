# 0027 — A box's infrastructure state lives outside the source checkout, and can be adopted back from the cloud

**Decision.**

1. **State is kept apart from the module.** OpenTofu runs against the box module (`infra/tofu/modules/<provider>-box`) with a
   local backend whose directory is Oz Box's own, `~/.local/state/ozbox/tofu/<module>/` (`$OZBOX_TOFU_STATE_DIR` or
   `$XDG_STATE_HOME` override it): one workspace per box under `workspaces/`, OpenTofu's working data under `data/`, and
   `backups/`. The modules declare an empty `backend "local" {}` and Oz Box passes the paths as `-backend-config`; run by hand,
   the module behaves as before. Removing, moving or re-cloning the checkout (a git worktree, a new release) can no longer
   take a box's state with it; a test removes the module directory and checks the state is still there.
2. **Existing installs move safely.** The first time a box module is used, state an older version left in the checkout
   (`terraform.tfstate.d/<box>/terraform.tfstate`) is copied to the new place, read back and compared, and the old files are
   **left where they were** with a note beside them. State already present in the new place is never overwritten.
3. **`ozbox adopt <box>` rebuilds missing state** (AWS), plan then apply. It reads the cloud (describe and list calls only),
   finds the box's resources by their `ozbox-*` tags and names, imports them into a new state in dependency order, corrects
   the artefacts an import leaves (`user_data` and `user_data_replace_on_change` on the machine, `stop_instance_before_detaching`
   on the attachment), then runs a plan. It finishes only if that plan changes nothing, or changes tags only; otherwise it
   takes what it imported back out of the state and says what the plan wanted. It never creates, changes or deletes a cloud
   resource, and it backs the state up before and after. A box that already has state is refused: there is nothing to adopt.
4. **The OpenTofu-state error points at it.** An upgrade that finds no state says so and names `ozbox adopt`.

**Why.** On a real box the state sat inside a git worktree of the repository; removing the worktree deleted the state of the
running box, and the next upgrade could not find it. Infrastructure state is the only record of which cloud resources a box
owns. It must not live in a directory people clone and delete, and losing it must be recoverable without guessing.

**Cost.** Two places can hold a box's state during the move (the old copy is kept on purpose; the new one is live). Adopt
exists only for AWS, where the resources are findable by tag; other providers would need their own finders. State is still a
local file: a shared encrypted bucket for box state is a separate decision.
